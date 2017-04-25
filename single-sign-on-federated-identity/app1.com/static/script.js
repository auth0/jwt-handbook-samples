//Auth0 Client ID
const clientId = "yufzO44QaHzxLTlUyPGpTz6vN6mNhjqU";
//Auth0 Domain
const domain = "speyrott.auth0.com";

const auth0 = new window.auth0.WebAuth({
    domain: domain,
    clientID: clientId,
    audience: 'app1.com/protected',
    scope: 'openid profile purchase',
    responseType: 'id_token token',
    redirectUri: 'http://app1.com:3000/auth/',
    responseMode: 'form_post'
});

let items = [];

function getItems() {
    return $.get('items.json').done(data => {
        if(Array.isArray(data)) {
            items = data;

            const select = $('#items-select');
            select.empty();
            items.forEach(item => {
                select.append(`<option value="${item.id}">${item.name}</option>`);
            });
        }
    });
}

const itemsDone = getItems();

function populateCart() {
    const cartElem = $('#cart');
    cartElem.empty();

    const cartToken = Cookies.get('cart');
    if(!cartToken) {
        return;
    }

    const cart = jwt_decode(cartToken).items;
    
    cart.forEach(itemId => {
        const name = items.find(item => item.id == itemId).name;
        cartElem.append(`<li>${name}</li>`);
    });
}

function loggedIn() {
    itemsDone.done(() => {
        populateCart();
    });
    $('#login-button').hide();
    $('#purchase-ui').show();    
    
    const name = jwt_decode(Cookies.get('id_token')).name;
    $('#purchase-ui h3').text(`Welcome ${name}`);
}

function loggedOut() {
    $('#login-button').show();
    $('#purchase-ui').hide();
}


$('#login-button').on('click', function(event) {
    auth0.authorize({
        prompt: 'none'
    });
});

$('#logout-button').on('click', function(event) {
    window.location.replace('/logout');
});

$('#add-item-button').on('click', function(event) {
    const selected = $('#items-select').val();

    $.get('/protected/add_item', { id: selected }).done(() => {
        populateCart();
    });
});

$('#clear-button').on('click', function(event) {
    Cookies.remove('cart');
    populateCart();
});

$('#purchase-button').on('click', function(event) {
    $.get('/protected/purchase').done(data => {
        alert(data);
        Cookies.remove('cart');
        populateCart();
    });
});

if(Cookies.get('id_token')) {
    loggedIn();
} else {
    loggedOut();
}
