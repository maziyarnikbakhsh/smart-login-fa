<?php
/**
 * Sign-in with a one-time code (OTP).
 *
 * Settings → General → "One-time code" picks how the code is used:
 *   off    — passwords only (the default).
 *   choice — a visitor may sign in with a code instead of a password.
 *   only   — a code is the only way in; the form has no password field.
 *   second — the password is checked first, then a code is required as well.
 *
 * A code goes out by SMS when the account has a mobile number the gateway can
 * reach (and, when the visitor typed an email, only if that fails), otherwise by
 * email. Codes live in a short-lived "ticket" (a transient) that the browser
 * holds the random id of; the code itself is stored only as a keyed hash.
 *
 * Nothing here reveals whether an account exists: asking for a code for an
 * unknown email or number answers exactly as it does for a real one.
 *
 * @package Smart_Login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SML_Login_Otp {

	const TICKET_PREFIX = 'sml_lotp_';

	/** Code requests per IP. */
	const REQUEST_LIMIT  = 10;
	const REQUEST_WINDOW = 3600; // 1 hour.

	public static function init() {
		add_action( 'wp_ajax_nopriv_sml_login_otp_send', array( __CLASS__, 'ajax_send' ) );
		add_action( 'wp_ajax_nopriv_sml_login_otp_resend', array( __CLASS__, 'ajax_resend' ) );
		add_action( 'wp_ajax_nopriv_sml_login_otp_verify', array( __CLASS__, 'ajax_verify' ) );
	}

	/**
	 * The mode in force. A mode that could never deliver a code — mobile-only
	 * sign-in with no SMS gateway set up, where the accounts have no usable
	 * email — falls back to 'off', so a half-finished setup cannot lock
	 * everyone out.
	 *
	 * @return string 'off'|'choice'|'only'|'second'
	 */
	public static function mode() {
		$value = (string) SML_Settings::get( 'login_otp', 'off' );

		if ( ! in_array( $value, array( 'choice', 'only', 'second' ), true ) ) {
			return 'off';
		}

		if ( ! SML_Settings::login_allows_email() && ! SML_SMS::is_configured() ) {
			return 'off';
		}

		return $value;
	}

	/** @return bool Whether a visitor can ask for a code instead of typing a password. */
	public static function code_login_enabled() {
		return in_array( self::mode(), array( 'choice', 'only' ), true );
	}

	/** @return bool Whether a password alone is refused. */
	public static function password_refused() {
		return 'only' === self::mode();
	}

	// ---------------------------------------------------------------- AJAX.

	/**
	 * Visitor asks for a code (identifier only, no password).
	 */
	public static function ajax_send() {
		check_ajax_referer( SML_Login_Handler::NONCE_ACTION, 'nonce' );

		if ( ! self::code_login_enabled() ) {
			wp_send_json_error( array( 'message' => __( 'Signing in with a code is not enabled.', 'smart-login' ) ) );
		}

		$who = self::identify();
		if ( is_wp_error( $who ) ) {
			wp_send_json_error( array( 'message' => $who->get_error_message() ) );
		}

		$bot_check = SML_Registration_Handler::check_bot_provider();
		if ( is_wp_error( $bot_check ) ) {
			wp_send_json_error( array( 'message' => $bot_check->get_error_message() ) );
		}

		$rate = SML_Rate_Limit::check( 'login_otp', self::REQUEST_LIMIT, self::REQUEST_WINDOW );
		if ( is_wp_error( $rate ) ) {
			wp_send_json_error( array( 'message' => $rate->get_error_message() ) );
		}

		$lock = SML_Lockout::check( $who['lock_key'] );
		if ( is_wp_error( $lock ) ) {
			wp_send_json_error( array( 'message' => $lock->get_error_message() ) );
		}

		// Same cooldown whether or not the account exists.
		$cooldown_key = 'sml_lotp_cd_' . md5( $who['lock_key'] );
		$cooldown     = (int) SML_Settings::get( 'resend_cooldown_seconds', 120 );
		$since        = get_transient( $cooldown_key );
		if ( is_numeric( $since ) && time() - (int) $since < $cooldown ) {
			wp_send_json_error(
				array(
					'message' => sprintf(
						/* translators: %d: seconds remaining */
						__( 'Please wait %d seconds before requesting another code.', 'smart-login' ),
						$cooldown - ( time() - (int) $since )
					),
				)
			);
		}

		SML_Rate_Limit::record( 'login_otp', self::REQUEST_WINDOW );
		set_transient( $cooldown_key, time(), $cooldown );

		$started = self::start( $who['user'], $who['prefer'], $who['lock_key'] );
		if ( is_wp_error( $started ) ) {
			wp_send_json_error( array( 'message' => $started->get_error_message() ) );
		}

		wp_send_json_success( $started );
	}

	/**
	 * A new code for a ticket the visitor already holds.
	 */
	public static function ajax_resend() {
		check_ajax_referer( SML_Login_Handler::NONCE_ACTION, 'nonce' );

		$ticket = self::read_ticket();
		if ( ! $ticket ) {
			wp_send_json_error( array( 'message' => __( 'This sign-in request has expired. Please start again.', 'smart-login' ), 'expired' => true ) );
		}

		$cooldown = (int) SML_Settings::get( 'resend_cooldown_seconds', 120 );
		$left     = $cooldown - ( time() - (int) $ticket['data']['sent_at'] );
		if ( $left > 0 ) {
			wp_send_json_error(
				array(
					'message'          => sprintf(
						/* translators: %d: seconds remaining */
						__( 'Please wait %d seconds before requesting another code.', 'smart-login' ),
						$left
					),
					'resend_available' => ( (int) $ticket['data']['sent_at'] + $cooldown ) * 1000,
				)
			);
		}

		$rate = SML_Rate_Limit::check( 'login_otp', self::REQUEST_LIMIT, self::REQUEST_WINDOW );
		if ( is_wp_error( $rate ) ) {
			wp_send_json_error( array( 'message' => $rate->get_error_message() ) );
		}
		SML_Rate_Limit::record( 'login_otp', self::REQUEST_WINDOW );

		$user = $ticket['data']['uid'] ? get_user_by( 'id', (int) $ticket['data']['uid'] ) : false;

		// The old ticket is replaced, so only the newest code ever works.
		delete_transient( self::TICKET_PREFIX . $ticket['id'] );

		$started = self::start( $user ? $user : null, (string) $ticket['data']['prefer'], (string) $ticket['data']['lock_key'], (string) $ticket['data']['redirect'] );
		if ( is_wp_error( $started ) ) {
			wp_send_json_error( array( 'message' => $started->get_error_message() ) );
		}

		wp_send_json_success( $started );
	}

	/**
	 * The visitor types the code.
	 */
	public static function ajax_verify() {
		check_ajax_referer( SML_Login_Handler::NONCE_ACTION, 'nonce' );

		$ticket = self::read_ticket();
		$code   = isset( $_POST['code'] ) ? preg_replace( '/\D/', '', SML_Iran::to_latin_digits( sanitize_text_field( wp_unslash( $_POST['code'] ) ) ) ) : '';

		if ( ! $ticket ) {
			wp_send_json_error( array( 'message' => __( 'This sign-in request has expired. Please start again.', 'smart-login' ), 'expired' => true ) );
		}

		$data     = $ticket['data'];
		$lock_key = (string) $data['lock_key'];

		$lock = SML_Lockout::check( $lock_key );
		if ( is_wp_error( $lock ) ) {
			wp_send_json_error( array( 'message' => $lock->get_error_message() ) );
		}

		$max = (int) SML_Settings::get( 'max_code_attempts', 5 );
		if ( (int) $data['attempts'] >= $max ) {
			delete_transient( self::TICKET_PREFIX . $ticket['id'] );
			wp_send_json_error( array( 'message' => __( 'Too many incorrect attempts. Please request a new code.', 'smart-login' ), 'expired' => true ) );
		}

		if ( (int) $data['expires'] < time() ) {
			delete_transient( self::TICKET_PREFIX . $ticket['id'] );
			wp_send_json_error( array( 'message' => __( 'This code has expired. Please request a new one.', 'smart-login' ) ) );
		}

		if ( '' === $code || ! hash_equals( (string) $data['code_hash'], self::hash( $code ) ) ) {
			$data['attempts'] = (int) $data['attempts'] + 1;
			set_transient( self::TICKET_PREFIX . $ticket['id'], $data, max( 60, (int) $data['expires'] - time() + 60 ) );
			SML_Lockout::register_failure( $lock_key );

			wp_send_json_error( array( 'message' => __( 'That code is incorrect.', 'smart-login' ) ) );
		}

		delete_transient( self::TICKET_PREFIX . $ticket['id'] );

		$user = (int) $data['uid'] ? get_user_by( 'id', (int) $data['uid'] ) : false;
		if ( ! $user ) {
			wp_send_json_error( array( 'message' => __( 'That code is incorrect.', 'smart-login' ) ) );
		}

		if ( ! SML_Login_Handler::role_allowed( $user ) ) {
			wp_send_json_error( array( 'message' => __( 'Your account type is not permitted to log in through this form.', 'smart-login' ) ) );
		}

		SML_Lockout::clear( $lock_key );

		// The code reached their own mobile or inbox, which is the proof
		// verification asks for.
		if ( 'none' !== SML_Verification::method() && SML_Verification::has_verification_record( $user->ID ) && ! SML_Verification::is_verified( $user->ID ) ) {
			SML_Verification::complete( $user->ID );
			update_user_meta( $user->ID, 'sml_verified_via', 'login_code' );
		}

		self::sign_in( $user );

		$redirect = (string) $data['redirect'];

		wp_send_json_success(
			array(
				'redirect' => $redirect ? $redirect : ( SML_Settings::post_login_redirect_url() ? SML_Settings::post_login_redirect_url() : home_url( '/' ) ),
				'message'  => __( 'Login successful.', 'smart-login' ),
			)
		);
	}

	// ----------------------------------------------------------- Internals.

	/**
	 * Issues a code for a user (or, for an unknown account, only pretends to)
	 * and returns what the browser needs for the next step.
	 *
	 * @param WP_User|null $user     The account, or null when none matched.
	 * @param string       $prefer   'sms' or 'email': which channel to try first.
	 * @param string       $lock_key Lockout key for failed attempts.
	 * @param string       $redirect Where to go afterwards (validated).
	 * @return array|WP_Error
	 */
	public static function start( $user, $prefer, $lock_key, $redirect = '' ) {
		if ( '' === $redirect ) {
			$redirect = SML_Page_Guard::validate_redirect( isset( $_POST['redirect_to'] ) ? wp_unslash( $_POST['redirect_to'] ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		}

		$length = max( 4, min( 8, (int) SML_Settings::get( 'code_length', 6 ) ) );
		$code   = '';
		for ( $i = 0; $i < $length; $i++ ) {
			$code .= (string) random_int( 0, 9 );
		}

		$uid = 0;

		if ( $user instanceof WP_User ) {
			$channel = self::channel_for( $user, $prefer );
			if ( '' === $channel ) {
				return new WP_Error( 'sml_otp_no_channel', __( 'We could not send a code to this account. Please sign in with your password or contact the site.', 'smart-login' ) );
			}

			$sent = self::deliver( $user, $channel, $code );
			if ( is_wp_error( $sent ) ) {
				return $sent;
			}

			$uid = (int) $user->ID;
		}

		$expiry = (int) SML_Settings::get( 'code_expiry_minutes', 10 ) * MINUTE_IN_SECONDS;
		$now    = time();
		$id     = wp_generate_password( 32, false, false );

		set_transient(
			self::TICKET_PREFIX . $id,
			array(
				'uid'       => $uid,
				'code_hash' => self::hash( $uid ? $code : wp_generate_password( 16, false ) ),
				'expires'   => $now + $expiry,
				'attempts'  => 0,
				'sent_at'   => $now,
				'prefer'    => $prefer,
				'lock_key'  => $lock_key,
				'redirect'  => $redirect,
			),
			$expiry + 60
		);

		$cooldown = (int) SML_Settings::get( 'resend_cooldown_seconds', 120 );

		return array(
			'ticket'           => $id,
			'otp_required'     => true,
			'code_length'      => $length,
			'resend_available' => ( $now + $cooldown ) * 1000,
			'message'          => __( 'If an account matches, we have sent it a code. Enter the code below.', 'smart-login' ),
		);
	}

	/**
	 * Where this user's code can go: SMS when they have a number the gateway
	 * reaches, email when they have a real address. $prefer picks the first try.
	 *
	 * @param WP_User $user
	 * @param string  $prefer 'sms'|'email'
	 * @return string 'sms'|'email'|''
	 */
	protected static function channel_for( WP_User $user, $prefer ) {
		$e164 = SML_Verification::user_e164( $user->ID );
		$sms  = '' !== $e164 && SML_SMS::is_configured() && SML_SMS::can_send_to( $e164 );
		$mail = ! SML_Verification::has_placeholder_email( $user->ID ) && is_email( $user->user_email );

		if ( 'email' === $prefer ) {
			return $mail ? 'email' : ( $sms ? 'sms' : '' );
		}

		return $sms ? 'sms' : ( $mail ? 'email' : '' );
	}

	/**
	 * @return true|WP_Error
	 */
	protected static function deliver( WP_User $user, $channel, $code ) {
		if ( 'sms' === $channel ) {
			$sent = SML_SMS::send_code( SML_Verification::user_e164( $user->ID ), $code );

			return is_wp_error( $sent ) ? $sent : true;
		}

		if ( ! SML_Email::send_login_code( $user, $code ) ) {
			return new WP_Error( 'sml_otp_mail', __( 'We could not send the email. Please try again in a few minutes.', 'smart-login' ) );
		}

		return true;
	}

	/**
	 * Finds the account an identifier points to, the way the login form does,
	 * without any password.
	 *
	 * @return array{user:WP_User|null,prefer:string,lock_key:string}|WP_Error
	 */
	protected static function identify() {
		$mobile_tab = isset( $_POST['login_mode'] ) && 'mobile' === sanitize_key( wp_unslash( $_POST['login_mode'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

		if ( $mobile_tab && ! SML_Settings::login_allows_mobile() ) {
			return new WP_Error( 'sml_otp_id', __( 'Please enter your email address.', 'smart-login' ) );
		}
		if ( ! $mobile_tab && ! SML_Settings::login_allows_email() ) {
			return new WP_Error( 'sml_otp_id', __( 'Please enter your mobile number.', 'smart-login' ) );
		}

		$e164 = '';

		if ( $mobile_tab ) {
			$country_id = isset( $_POST['phone_country'] ) ? sanitize_key( wp_unslash( $_POST['phone_country'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
			if ( '' === $country_id ) {
				$country_id = SML_Countries::single();
			}
			$typed     = isset( $_POST['phone_number'] ) ? sanitize_text_field( wp_unslash( $_POST['phone_number'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$countries = SML_Countries::all();

			if ( '' === preg_replace( '/\D/', '', SML_Iran::to_latin_digits( $typed ) ) ) {
				return new WP_Error( 'sml_otp_id', __( 'Please enter your mobile number.', 'smart-login' ) );
			}

			$e164 = isset( $countries[ $country_id ] ) ? SML_Phone::e164_for( $countries[ $country_id ]['dial'], $typed ) : '';

			if ( 0 === strpos( $e164, '+98' ) && 1 !== preg_match( '/^\+989\d{9}$/', $e164 ) ) {
				return new WP_Error( 'sml_otp_id', SML_Phone::iranian_mobile_error( $typed ) );
			}
		} else {
			$username = isset( $_POST['username'] ) ? sanitize_text_field( wp_unslash( $_POST['username'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
			if ( false !== strpos( $username, '@' ) ) {
				$username = SML_Iran::to_latin_digits( $username );
			}
			if ( '' === $username ) {
				return new WP_Error( 'sml_otp_id', __( 'Please enter your email address.', 'smart-login' ) );
			}

			if ( SML_Settings::login_allows_mobile() ) {
				$e164 = SML_Phone::parse_e164( $username );
			}
		}

		$user = null;

		if ( '' !== $e164 ) {
			SML_Phone::maybe_backfill_e164();
			$user = SML_Phone::primary_user_for( $e164 );

			return array(
				'user'     => $user ? $user : null,
				'prefer'   => 'sms',
				'lock_key' => $e164,
			);
		}

		$found = is_email( $username ) ? get_user_by( 'email', $username ) : get_user_by( 'login', $username );

		return array(
			'user'     => $found ? $found : null,
			'prefer'   => 'email',
			'lock_key' => $username,
		);
	}

	/**
	 * @return array{id:string,data:array}|null
	 */
	protected static function read_ticket() {
		$id = isset( $_POST['ticket'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', wp_unslash( $_POST['ticket'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		if ( 32 !== strlen( $id ) ) {
			return null;
		}

		$data = get_transient( self::TICKET_PREFIX . $id );

		return is_array( $data ) && isset( $data['code_hash'], $data['expires'], $data['lock_key'] ) ? array(
			'id'   => $id,
			'data' => $data,
		) : null;
	}

	protected static function hash( $value ) {
		return hash_hmac( 'sha256', (string) $value, wp_salt( 'auth' ) );
	}

	/**
	 * Opens the session, the same way a normal sign-in ends.
	 *
	 * @param WP_User $user
	 */
	public static function sign_in( WP_User $user ) {
		wp_set_current_user( $user->ID, $user->user_login );
		wp_set_auth_cookie( $user->ID, true, is_ssl() );

		/** This action is documented in wp-includes/user.php */
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
	}
}
