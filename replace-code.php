// ============ 2FA LOGIN PROCESS ============
function al_handle_2fa_login($user_login, $user) {
    // Check if 2FA is enabled for this user
    if (al_is_2fa_enabled_for_user($user->ID)) {
        // Generate and send 2FA code
        $code = al_generate_2fa_code($user->ID);
        al_send_2fa_code($user->ID, $code);
        
        // Store user ID in session for 2FA verification
        if (!session_id()) {
            session_start();
        }
        $_SESSION['al_2fa_user_id'] = $user->ID;
        $_SESSION['al_2fa_user_login'] = $user_login;
        
        // Clear auth cookies to prevent immediate login
        wp_clear_auth_cookie();
        
        // Redirect to 2FA verification page
        wp_redirect(wp_login_url() . '?2fa_verify=1');
        exit;
    }
}
add_action('wp_login', 'al_handle_2fa_login', 5, 2);

// Add 2FA verification form to login page
function al_add_2fa_login_form() {
    if (isset($_GET['2fa_verify']) && $_GET['2fa_verify'] == '1') {
        if (!session_id()) {
            session_start();
        }
        
        if (isset($_SESSION['al_2fa_user_id'])) {
            $user_id = $_SESSION['al_2fa_user_id'];
            $user_login = $_SESSION['al_2fa_user_login'];
            $user = get_userdata($user_id);
            ?>
            <style>
            #loginform {
                display: none !important;
            }
            #2fa-verification {
                background: #f9f9f9;
                border: 1px solid #ccd0d4;
                padding: 20px;
                margin: 20px 0;
                border-radius: 5px;
            }
            #2fa-verification h3 {
                color: #23282d;
                margin-top: 0;
            }
            .2fa-error {
                background: #ffeaa7;
                border: 1px solid #fdcb6e;
                padding: 10px;
                margin: 10px 0;
                border-radius: 3px;
            }
            </style>
            
            <div id="2fa-verification">
                <h3>🔐 Two-Factor Authentication Required</h3>
                <p>Hello <strong><?php echo esc_html($user->display_name); ?></strong>,</p>
                <p>We've sent a 6-digit verification code to your email: <strong><?php echo esc_html($user->user_email); ?></strong></p>
                <p>Please check your email and enter the code below:</p>
                
                <?php 
                // Show error if code is wrong
                if (isset($_POST['al_2fa_code']) && !empty($_POST['al_2fa_code'])) {
                    echo '<div class="2fa-error">❌ Invalid verification code. Please try again.</div>';
                }
                
                // Show success message if code was resent
                if (isset($_GET['resent']) && $_GET['resent'] == '1') {
                    echo '<div style="background: #d1ecf1; border: 1px solid #bee5eb; padding: 10px; margin: 10px 0; border-radius: 3px;">✅ New verification code sent to your email!</div>';
                }
                ?>
                
                <form method="post" id="2fa-form">
                    <p>
                        <label for="al_2fa_code"><strong>Verification Code:</strong></label>
                        <input type="text" name="al_2fa_code" id="al_2fa_code" size="20" 
                               required pattern="[0-9]{6}" title="6-digit code" 
                               placeholder="Enter 6-digit code" style="font-size: 18px; padding: 10px; text-align: center; letter-spacing: 5px;">
                    </p>
                    <p>
                        <input type="submit" name="wp-submit" id="wp-submit" 
                               class="button button-primary button-large" value="✅ Verify & Login">
                        <input type="hidden" name="al_2fa_verify" value="1">
                        <input type="hidden" name="log" value="<?php echo esc_attr($user_login); ?>">
                    </p>
                </form>
                
                <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid #ddd;">
                    <p style="font-size: 13px; color: #666;">
                        Didn't receive the code? 
                        <a href="<?php echo wp_login_url(); ?>?2fa_resend=1" style="color: #0073aa;">📧 Resend Code</a>
                        <br>
                        <small>Code expires in 10 minutes</small>
                    </p>
                </div>
            </div>
            
            <script type="text/javascript">
            document.addEventListener('DOMContentLoaded', function() {
                // Hide the regular login form
                var loginForm = document.getElementById('loginform');
                if (loginForm) {
                    loginForm.style.display = 'none';
                }
                
                // Focus on OTP input
                var otpInput = document.getElementById('al_2fa_code');
                if (otpInput) {
                    otpInput.focus();
                }
                
                // Auto-submit when 6 digits entered
                otpInput.addEventListener('input', function() {
                    if (this.value.length === 6) {
                        document.getElementById('2fa-form').submit();
                    }
                });
            });
            </script>
            <?php
        }
    }
}
add_action('login_form', 'al_add_2fa_login_form');

// Handle 2FA code verification
function al_verify_2fa_code($user, $username, $password) {
    if (isset($_POST['al_2fa_verify']) && $_POST['al_2fa_verify'] == '1') {
        if (!session_id()) {
            session_start();
        }
        
        if (isset($_SESSION['al_2fa_user_id']) && isset($_POST['al_2fa_code'])) {
            $user_id = $_SESSION['al_2fa_user_id'];
            $stored_code = get_transient('al_2fa_code_' . $user_id);
            $entered_code = sanitize_text_field($_POST['al_2fa_code']);
            
            if ($stored_code && $stored_code === $entered_code) {
                // Code is valid - complete login
                delete_transient('al_2fa_code_' . $user_id);
                $user = get_user_by('id', $user_id);
                
                // Clear 2FA session
                unset($_SESSION['al_2fa_user_id']);
                unset($_SESSION['al_2fa_user_login']);
                
                al_log_activity($user_id, $user->user_login, '2FA Verified - Login Completed');
                return $user;
            } else {
                // Invalid code
                al_log_activity($user_id, $_SESSION['al_2fa_user_login'], '2FA Failed: Invalid Code Entered');
                return new WP_Error('authentication_failed', 
                    '<strong>ERROR</strong>: Invalid verification code. Please try again.');
            }
        }
    }
    return $user;
}
add_filter('authenticate', 'al_verify_2fa_code', 30, 3);

// Handle 2FA code resend
function al_handle_2fa_resend() {
    if (isset($_GET['2fa_resend']) && $_GET['2fa_resend'] == '1') {
        if (!session_id()) {
            session_start();
        }
        
        if (isset($_SESSION['al_2fa_user_id'])) {
            $user_id = $_SESSION['al_2fa_user_id'];
            $code = al_generate_2fa_code($user_id);
            al_send_2fa_code($user_id, $code);
            
            // Redirect back to verification page
            wp_redirect(wp_login_url() . '?2fa_verify=1&resent=1');
            exit;
        }
    }
}
add_action('login_init', 'al_handle_2fa_resend');