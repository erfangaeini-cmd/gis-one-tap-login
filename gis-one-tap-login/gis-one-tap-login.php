<?php
/**
 * Plugin Name: GIS One Tap Auto Login
 * Description: Google One Tap Login for WordPress + Dashboard Widget (quick settings + inline help). Parse-safe (no heredoc).
 * Version: 1.3.3
 * Author: erfan gaeini
 * Website: https://teamkala-co.com/
 * GitHub:  https://github.com/erfangaeini-cmd
 */

if (!defined('ABSPATH')) exit;

/** ---------- Constants ---------- */
if (!defined('GIS_OPTION_KEY')) {
  define('GIS_OPTION_KEY', 'gis_one_tap_options');
}

/** ---------- Defaults ---------- */
if (!function_exists('gis_defaults')) {
  function gis_defaults() {
    return array(
      'client_id'             => '',
      'auto_select'           => 1,
      'cancel_on_tap_outside' => 1,
      'itp_support'           => 1,
      'prompt_on_load'        => 1,
    );
  }
}

/** ---------- Frontend enqueue (logged-out only) ---------- */
add_action('wp_enqueue_scripts', 'gis_enqueue_scripts');
if (!function_exists('gis_enqueue_scripts')) {
  function gis_enqueue_scripts() {
    if (is_user_logged_in() || is_admin()) return;

    $opts = wp_parse_args(get_option(GIS_OPTION_KEY, array()), gis_defaults());
    if (empty($opts['client_id'])) return;

    // 1) Load Google script
    wp_enqueue_script('gis', 'https://accounts.google.com/gsi/client', array(), null, true);

    // 2) Pass config before script (no heredoc)
    $config = array(
      'ajax'               => admin_url('admin-ajax.php'),
      'client_id'          => (string) $opts['client_id'],
      'auto_select'        => (bool) $opts['auto_select'],
      'cancel_on_tap_outside' => (bool) $opts['cancel_on_tap_outside'],
      'itp_support'        => (bool) $opts['itp_support'],
      'prompt_on_load'     => (bool) $opts['prompt_on_load'],
    );
    $cfg_js = 'window.GIS_CONFIG=' . wp_json_encode($config) . ';';
    wp_add_inline_script('gis', $cfg_js, 'before');

    // 3) Init code after script (string concatenation only)
    $init  = '';
    $init .= "(function(){";
    $init .= "function ready(fn){if(document.readyState!='loading'){fn();}else{document.addEventListener('DOMContentLoaded',fn);}}";
    $init .= "ready(function(){";
    $init .= " if(!window.google||!google.accounts||!google.accounts.id) return;";
    $init .= " var C=window.GIS_CONFIG||{};";
    $init .= " google.accounts.id.initialize({";
    $init .= "  client_id: C.client_id||'',";
    $init .= "  callback: function(resp){";
    $init .= "    try{";
    $init .= "      fetch(String(C.ajax)+'?action=gis_one_tap_login',{";
    $init .= "        method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',";
    $init .= "        body: JSON.stringify({credential: resp.credential})";
    $init .= "      }).then(function(r){return r.json()}).then(function(d){ if(d&&d.success){window.location.reload();} });";
    $init .= "    }catch(e){ if(window.console) console.log(e); }";
    $init .= "  },";
    $init .= "  auto_select: !!C.auto_select,";
    $init .= "  cancel_on_tap_outside: !!C.cancel_on_tap_outside,";
    $init .= "  itp_support: !!C.itp_support";
    $init .= " });";
    $init .= " if(C.prompt_on_load){ google.accounts.id.prompt(); }";
    $init .= "});";
    $init .= "})();";

    wp_add_inline_script('gis', $init, 'after');
  }
}

/** ---------- AJAX: verify & login ---------- */
add_action('wp_ajax_nopriv_gis_one_tap_login', 'gis_one_tap_login_handler');
if (!function_exists('gis_one_tap_login_handler')) {
  function gis_one_tap_login_handler() {
    $raw  = file_get_contents('php://input');
    $body = json_decode($raw, true);
    $id_token = isset($body['credential']) ? $body['credential'] : '';
    if (!$id_token) wp_send_json_error(array('msg' => 'no_token'));

    $res = wp_remote_get('https://oauth2.googleapis.com/tokeninfo?id_token=' . urlencode($id_token), array('timeout' => 10));
    if (is_wp_error($res)) wp_send_json_error(array('msg' => 'verify_failed'));

    $data = json_decode(wp_remote_retrieve_body($res), true);
    $opts = wp_parse_args(get_option(GIS_OPTION_KEY, array()), gis_defaults());

    if (!isset($data['aud']) || $data['aud'] !== (string)$opts['client_id']) {
      wp_send_json_error(array('msg' => 'invalid_aud'));
    }
    if (!isset($data['email_verified']) || $data['email_verified'] !== 'true') {
      wp_send_json_error(array('msg' => 'unverified'));
    }

    $email = sanitize_email(isset($data['email']) ? $data['email'] : '');
    $name  = sanitize_text_field(isset($data['name']) ? $data['name'] : '');
    if (!$email) wp_send_json_error(array('msg' => 'invalid_email'));

    $user = get_user_by('email', $email);
    if (!$user) {
      $username = sanitize_user(current(explode('@', $email)));
      if (username_exists($username)) $username .= '_' . wp_generate_password(4, false, false);
      $user_id = wp_create_user($username, wp_generate_password(), $email);
      if (is_wp_error($user_id)) wp_send_json_error(array('msg' => 'user_create_failed'));
      if (!empty($name)) wp_update_user(array('ID' => $user_id, 'display_name' => $name));
      $user = get_user_by('id', $user_id);
    }

    wp_set_auth_cookie($user->ID, true);
    wp_send_json_success(array('success' => true));
  }
}

/** ---------- Settings page (kept) ---------- */
add_action('admin_menu', 'gis_register_settings_page');
if (!function_exists('gis_register_settings_page')) {
  function gis_register_settings_page() {
    add_options_page(
      'GIS One Tap Login',
      'GIS One Tap Login',
      'manage_options',
      'gis-one-tap',
      'gis_render_settings_page'
    );
  }
}

add_action('admin_init', 'gis_register_settings');
if (!function_exists('gis_register_settings')) {
  function gis_register_settings() {
    register_setting(
      'gis_one_tap_group',
      GIS_OPTION_KEY,
      array(
        'type'              => 'array',
        'sanitize_callback' => 'gis_sanitize_options',
        'default'           => gis_defaults(),
        'show_in_rest'      => false,
      )
    );

    add_settings_section(
      'gis_main_section',
      'Google Identity Services (One Tap) Settings',
      function () {
        echo '<p>Configure Google One Tap. Use a <strong>Web OAuth 2.0 Client ID</strong> from Google Cloud Console.</p>';
      },
      'gis-one-tap'
    );

    add_settings_field('client_id', 'Client ID', 'gis_field_client_id', 'gis-one-tap', 'gis_main_section');
    add_settings_field('auto_select', 'Auto Select', 'gis_field_checkbox', 'gis-one-tap', 'gis_main_section', array('key' => 'auto_select', 'label' => 'Enable auto-select'));
    add_settings_field('cancel_on_tap_outside', 'Cancel on Tap Outside', 'gis_field_checkbox', 'gis-one-tap', 'gis_main_section', array('key' => 'cancel_on_tap_outside', 'label' => 'Dismiss on outside tap'));
    add_settings_field('itp_support', 'ITP Support', 'gis_field_checkbox', 'gis-one-tap', 'gis_main_section', array('key' => 'itp_support', 'label' => 'Enable ITP support (Safari)'));
    add_settings_field('prompt_on_load', 'Prompt on Load', 'gis_field_checkbox', 'gis-one-tap', 'gis_main_section', array('key' => 'prompt_on_load', 'label' => 'Call google.accounts.id.prompt() automatically'));
  }
}

if (!function_exists('gis_sanitize_options')) {
  function gis_sanitize_options($input) {
    $d = gis_defaults();
    return array(
      'client_id'             => isset($input['client_id']) ? sanitize_text_field($input['client_id']) : $d['client_id'],
      'auto_select'           => !empty($input['auto_select']) ? 1 : 0,
      'cancel_on_tap_outside' => !empty($input['cancel_on_tap_outside']) ? 1 : 0,
      'itp_support'           => !empty($input['itp_support']) ? 1 : 0,
      'prompt_on_load'        => !empty($input['prompt_on_load']) ? 1 : 0,
    );
  }
}

if (!function_exists('gis_field_client_id')) {
  function gis_field_client_id() {
    $o = wp_parse_args(get_option(GIS_OPTION_KEY, array()), gis_defaults());
    printf(
      '<input type="text" name="%1$s[client_id]" value="%2$s" class="regular-text" placeholder="1234567890-abc.apps.googleusercontent.com" />',
      esc_attr(GIS_OPTION_KEY),
      esc_attr($o['client_id'])
    );
    echo '<p class="description">Paste your <strong>Web Client ID</strong>.</p>';
  }
}

if (!function_exists('gis_field_checkbox')) {
  function gis_field_checkbox($args) {
    $key = isset($args['key']) ? $args['key'] : '';
    $label = isset($args['label']) ? $args['label'] : '';
    $o = wp_parse_args(get_option(GIS_OPTION_KEY, array()), gis_defaults());
    printf(
      '<label><input type="checkbox" name="%1$s[%2$s]" value="1" %3$s /> %4$s</label>',
      esc_attr(GIS_OPTION_KEY),
      esc_attr($key),
      checked(1, (int)$o[$key], false)
      ,
      esc_html($label)
    );
  }
}

if (!function_exists('gis_render_settings_page')) {
  function gis_render_settings_page() {
    if (!current_user_can('manage_options')) return;
    echo '<div class="wrap"><h1>GIS One Tap Login</h1><form method="post" action="options.php">';
    settings_fields('gis_one_tap_group');
    do_settings_sections('gis-one-tap');
    submit_button('Save Settings');
    echo '</form></div>';
  }
}

/** ---------- Dashboard Widget (with inline Help) ---------- */
add_action('wp_dashboard_setup', 'gis_register_dashboard_widget');
if (!function_exists('gis_register_dashboard_widget')) {
  function gis_register_dashboard_widget() {
    if (!current_user_can('manage_options')) return;
    wp_add_dashboard_widget('gis_one_tap_widget', 'GIS One Tap – Settings & Help', 'gis_render_dashboard_widget');
  }
}

if (!function_exists('gis_mask_client_id')) {
  function gis_mask_client_id($id) {
    $id = (string)$id;
    if ($id === '') return '';
    $len = strlen($id);
    if ($len <= 16) return esc_html($id);
    return esc_html(substr($id, 0, 8) . str_repeat('•', max(0, $len - 16)) . substr($id, -8));
  }
}

if (!function_exists('gis_render_dashboard_widget')) {
  function gis_render_dashboard_widget() {
    if (!current_user_can('manage_options')) return;
    $o = wp_parse_args(get_option(GIS_OPTION_KEY, array()), gis_defaults());
    $enabled = !empty($o['client_id']);

    echo '<div style="font-size:14px;">';
    echo '<p><strong>Status:</strong> ' . ($enabled ? '<span style="color:#46b450;font-weight:600;">Active</span>' : '<span style="color:#dc3232;font-weight:600;">Not Configured</span>') . '</p>';
    echo '<p><strong>Client ID:</strong> ' . gis_mask_client_id($o['client_id']) . '</p>';

    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
    wp_nonce_field('gis_dash_save', 'gis_dash_nonce');
    echo '<input type="hidden" name="action" value="gis_dash_save" />';
    echo '<p><label>Client ID<br><input type="text" name="client_id" value="' . esc_attr($o['client_id']) . '" class="regular-text" placeholder="1234567890-abc.apps.googleusercontent.com"></label></p>';
    echo '<p><label><input type="checkbox" name="auto_select" value="1" ' . checked(1, (int)$o['auto_select'], false) . '> Auto Select</label></p>';
    echo '<p><label><input type="checkbox" name="cancel_on_tap_outside" value="1" ' . checked(1, (int)$o['cancel_on_tap_outside'], false) . '> Cancel on Tap Outside</label></p>';
    echo '<p><label><input type="checkbox" name="itp_support" value="1" ' . checked(1, (int)$o['itp_support'], false) . '> ITP Support</label></p>';
    echo '<p><label><input type="checkbox" name="prompt_on_load" value="1" ' . checked(1, (int)$o['prompt_on_load'], false) . '> Prompt on Load</label></p>';
    submit_button('Save', 'primary', '', false);
    echo '</form>';

    echo '<hr><h3 style="margin-top:16px;">📌 راهنمای جامع ساخت Google Web Client ID (One Tap)</h3>';
    echo '<ol style="line-height:1.7em;font-size:13px;margin:0;padding-left:20px;">';
    echo '<li><strong>ورود:</strong> <a href="https://console.cloud.google.com/" target="_blank" rel="noopener noreferrer">console.cloud.google.com</a></li>';
    echo '<li><strong>پروژه:</strong> ایجاد/انتخاب Project.</li>';
    echo '<li><strong>OAuth consent screen:</strong> نوع <em>External</em>، افزودن دامنه (مثال <code>teamkala-co.com</code>) در Authorized domains، Save.</li>';
    echo '<li><strong>Credentials → Create Credentials → OAuth client ID:</strong> نوع <em>Web application</em>.</li>';
    echo '<li><strong>Authorized JavaScript origins:</strong><ul style="margin-top:.4em;"><li><code>https://teamkala-co.com</code></li><li><code>https://www.teamkala-co.com</code></li><li>origin‌های staging/subdomain (فقط HTTPS؛ localhost مجاز است).</li></ul></li>';
    echo '<li><strong>Create:</strong> Client ID را کپی و در فرم بالا Paste و ذخیره کنید.</li>';
    echo '<li><strong>Testing vs Production:</strong> اگر Testing است، حساب خود را در Test users اضافه کنید یا به In production تغییر دهید.</li>';
    echo '</ol>';

    echo '<details style="margin-top:12px;"><summary><strong>🔧 عیب‌یابی سریع</strong></summary>';
    echo '<ul style="line-height:1.7em;font-size:13px;margin-top:.6em;">';
    echo '<li><strong>invalid_client / missing_client_id / unregistered_origin:</strong> Client ID و Originها را دقیق با HTTPS وارد کنید.</li>';
    echo '<li><strong>cookies_blocked / browser_not_supported:</strong> در Chrome بدون ad-block تست کنید؛ third-party cookies فعال باشد.</li>';
    echo '<li><strong>عدم نمایش پنجره:</strong> موقتاً Auto Select را خاموش و مجدد تست کنید.</li>';
    echo '<li><strong>CSP/Firewall:</strong> اجازه به <code>https://accounts.google.com</code> و <code>https://apis.google.com</code> در script-src/frame-src.</li>';
    echo '</ul></details>';

    echo '<p style="font-size:12px;color:#666;margin-top:8px;">ℹ️ One Tap فقط برای کاربران خارج از سیستم (logged-out) در فرانت‌اند قابل مشاهده است.</p>';
    echo '</div>';
  }
}

/** ---------- Dashboard save handler ---------- */
add_action('admin_post_gis_dash_save', 'gis_dashboard_save_handler');
if (!function_exists('gis_dashboard_save_handler')) {
  function gis_dashboard_save_handler() {
    if (!current_user_can('manage_options')) wp_die('Forbidden');
    check_admin_referer('gis_dash_save', 'gis_dash_nonce');

    $curr = wp_parse_args(get_option(GIS_OPTION_KEY, array()), gis_defaults());
    $next = array(
      'client_id'             => isset($_POST['client_id']) ? sanitize_text_field(wp_unslash($_POST['client_id'])) : $curr['client_id'],
      'auto_select'           => !empty($_POST['auto_select']) ? 1 : 0,
      'cancel_on_tap_outside' => !empty($_POST['cancel_on_tap_outside']) ? 1 : 0,
      'itp_support'           => !empty($_POST['itp_support']) ? 1 : 0,
      'prompt_on_load'        => !empty($_POST['prompt_on_load']) ? 1 : 0,
    );
    update_option(GIS_OPTION_KEY, gis_sanitize_options($next));
    wp_safe_redirect(add_query_arg(array('updated' => 'true'), wp_get_referer() ? wp_get_referer() : admin_url('index.php')));
    exit;
  }
}

/** ---------- Uninstall cleanup ---------- */
register_uninstall_hook(__FILE__, 'gis_uninstall');
if (!function_exists('gis_uninstall')) {
  function gis_uninstall() {
    delete_option(GIS_OPTION_KEY);
  }
}
