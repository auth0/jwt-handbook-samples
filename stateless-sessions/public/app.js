  
var lock = new Auth0Lock(AUTH0_CLIENT_ID, AUTH0_DOMAIN, {
  auth: {
    params: { scope: 'openid name email' } //Details: https://auth0.com/docs/scopes
  }
});

lock.on("authenticated", function(authResult) {
  lock.getProfile(authResult.idToken, function(error, profile) {
    if (error) {
      // Handle error
      return;
    }
    localStorage.setItem('id_token', authResult.idToken);
    // Display user information
    showLoggedIn(profile);
  });
});

//retrieve the profile:
var retrieveProfile = function() {
  var id_token = localStorage.getItem('id_token');
  if (id_token) {
    lock.getProfile(id_token, function (err, profile) {
      if (err) {
        return alert('There was an error getting the profile: ' + err.message);
      }
      // Display user information
      showLoggedIn(profile);      
    });
  }
};

var showLoggedIn = function(profile) {
   $('.nickname').text(profile.nickname);
   $('.btn-login').hide();
   $('.avatar').attr('src', profile.picture).show();
   $('.btn-logout').show();
   $('a').show();
};

var logout = function() {
  localStorage.removeItem('id_token');
  window.location.href = "/";
};

function initIndex() {
  $('.btn-login').click(function(e) {
    e.preventDefault();
    lock.show();
  });

  $('.btn-logout').click(function(e) {
    e.preventDefault();
    logout();
  });
  retrieveProfile();
}

$.ajaxSetup({
    beforeSend: function(xhr) {
        var token = localStorage.getItem('id_token');
        if(token) {
          xhr.setRequestHeader('Authorization', 
            'Bearer ' + token);
        }
    }
});

function initShop() {
  $('form').submit(function(event) {
    $.ajax({
      type: 'POST',
      url: '/secured/add-item',
      data: $('form').serialize(),
      success: function(data) {
        localStorage.setItem('id_token', data.id_token);
      }
    });
    event.preventDefault();
  });
}

function initShowCart() {
  var token = localStorage.getItem('id_token');
  if(token) {
    var decoded = jwt_decode(token);
    var body = $('#items');
    decoded.items.forEach(function(item) {
      body.append('<li>' + item + '</li>');
    });
  }
}
