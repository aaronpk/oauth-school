
document.getElementById('pkce-generate-random-string').addEventListener('click', function(){
  document.getElementById('pkce-plaintext').value = generateRandomString();
});

document.getElementById('pkce-calculate-sha256').addEventListener('click', function(){
  if(document.getElementById('pkce-plaintext').value != "") {
    pkce_challenge_from_verifier(document.getElementById('pkce-plaintext').value)
      .then(base64urlencoded => document.getElementById('pkce-sha256').value = base64urlencoded);
  }
});

function generateRandomString() {
  var array = new Uint32Array(56/2);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec2hex).join('');
}

function dec2hex(dec) {
  return ('0' + dec.toString(16)).substr(-2)
}

function sha256(plain) { // returns promise ArrayBuffer
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return window.crypto.subtle.digest('SHA-256', data);
}

function base64urlencode(a) {
  // Convert the ArrayBuffer to string using Uint8 array.
  // btoa takes chars from 0-255 and base64 encodes.
  // Then convert the base64 encoded to base64url encoded.
  // (replace + with -, replace / with _, trim trailing =)
  return btoa(String.fromCharCode.apply(null, new Uint8Array(a)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function pkce_challenge_from_verifier(v) {
  hashed = await sha256(v);
  base64encoded = base64urlencode(hashed);
  return base64encoded;
}
