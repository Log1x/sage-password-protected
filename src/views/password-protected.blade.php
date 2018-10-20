<!doctype html>
<html @php(language_attributes())>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>{{ $password->title() }}</title>
    <meta name="robots" content="noindex, nofollow" />

    @php(wp_admin_css('login', true))
    @php(do_action('login_enqueue_scripts'))
  </head>

  <body class="login login-password-protected wp-core-ui" itemscope itemtype="http://schema.org/WebPage">
    <div id="login">
      <h1>
        <a href="{{ $password->url() }}" title="{{ $password->name() }}" tabindex="-1">
          {{ $password->name() }}
        </a>
      </h1>

      @if ($code = $password->errors->get_error_code())
        <div id="login_error">
          {{ $password->errors->get_error_message($code) }}
        </div>
      @endif

      <form id="loginform" name="loginform" action="{{ $password->url() }}" method="post">
        <p>
          <label for="password">{{ __('Password', 'app') }}</label>
          <input type="password" name="password" id="password" class="input" value="" size="20" tabindex="20" />
        </p>

        <p class="submit">
          <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log in" tabindex="100" />
          <input type="hidden" name="password_protected" value="login" />
          <input type="hidden" name="redirect_to" value="{{ $password->redirectUrl() }}" />
        </p>
      </form>
    </div>

    @php(do_action('login_footer'))
  </body>
</html>
