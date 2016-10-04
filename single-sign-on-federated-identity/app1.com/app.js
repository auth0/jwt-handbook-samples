$(document).ready(function() {

    // hide the page in case there is an SSO session (to avoid flickering)
    //document.body.style.display = 'none';

    // instantiate Lock
    var lock = new Auth0Lock('ye0F16vzCTBX5yTejqEfc18wEWIOwJWI', 'speyrott.auth0.com', {
      auth: {
        redirectUrl: 'http://app1.com:3000/',
        responseType: 'token',
        sso: true,
        params: {
          scope: 'openid name email' // Learn about scopes: https://auth0.com/docs/scopes
        }
      }
    });

    // Listening for the authenticated event
    lock.on("authenticated", function (authResult) {
      localStorage.setItem('idToken', authResult.idToken);
      goToHomepage(getQueryParameter('targetUrl'), authResult.idToken);
    });

    var client = new Auth0({
      domain: 'speyrott.auth0.com',
      clientID: 'ye0F16vzCTBX5yTejqEfc18wEWIOwJWI',
      callbackURL: 'http://app1.com:3000/',
      responseType: 'token'
    });

    // Get the user token if we've saved it in localStorage before
    var idToken = localStorage.getItem('idToken');
    if (idToken) {
      // This would go to a different route like
      // window.location.href = '#home';
      // But in this case, we just hide and show things
      goToHomepage(getQueryParameter('targetUrl'), idToken);
      return;
    } else {
      client.getSSOData(function (err, data) {
        if (!err && data.sso) {
          // there is! redirect to Auth0 for SSO
          client.signin({
            responseType: 'token',
            scope: 'openid name email'
          }, function (err, profile, idToken) {
            if (!err) {
              localStorage.setItem('idToken', idToken);
              goToHomepage('', idToken);
            }
          });
        }
      });
    }

    // Showing Login
    $('.btn-login').click(function(e) {
      e.preventDefault();
      lock.show();
    });


    // Sending token in header if available
    $.ajaxSetup({
      'beforeSend': function(xhr) {
        if (localStorage.getItem('userToken')) {
          xhr.setRequestHeader('Authorization',
                'Bearer ' + localStorage.getItem('userToken'));
        }
      }
    });

    $('.btn-api').click(function(e) {
        // Just call your API here. The header will be sent
    });

    function goToHomepage(state, token) {
      // Instead of redirect, we just show boxes
      document.body.style.display = 'inline';
      $('.login-box').hide();
      $('.logged-in-box').show();
      var profile = jwt_decode(token);
      $('.name').text(profile.name);
      if (state) {
        $('.url').show();
        $('.url span').text(state);
      }
    }

    function getQueryParameter(name) {
      name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
      var regex = new RegExp("[\\?&]" + name + "=([^&]*)"),
          results = regex.exec(location.search);
      return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
    }


});
