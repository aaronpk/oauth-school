<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use ORM;

class WebFlowController extends ExerciseController {

  use AuthorizationFlowTrait;

  private $pageTitle = 'Authorization Code Flow for Web Apps';
  private $baseRoute = 'web';

  public function save(Request $request): Response {

    $redirectToRoute = $this->baseRoute;

    $scopes = $this->session->get('scopes');

    $tokenResponse = $request->request->get('tokenResponse');

    if(!$tokenResponse) {
      return $this->_respondWithError($redirectToRoute,
        'Please enter the full token response',
        $tokenResponse);
    }

    // Attempt to parse as JSON
    $response = json_decode($tokenResponse, true);

    if(!$response || !is_array($response)) {
      return $this->_respondWithError($redirectToRoute,
        'Make sure you enter the full response from the token endpoint, not just the access token',
        $tokenResponse);
    }

    // Check that the response includes an access token
    if(!isset($response['access_token'])) {
      return $this->_respondWithError($redirectToRoute,
        'The token response does not contain an access token. Check for any error messages in the token response and try again.',
        $tokenResponse);
    }

    // Check that the response does not include a refresh token
    if(isset($response['refresh_token'])) {
      return $this->_respondWithError($redirectToRoute,
        'We found a refresh token, but you should not have one at this point. Make sure you\'ve followed the instructions for this exercise exactly and are requesting only an access token.',
        $tokenResponse);
    }

    // Check that the response does not include an ID token
    if(isset($response['id_token'])) {
      return $this->_respondWithError($redirectToRoute,
        'We found an ID token, but you should not have one at this point. Make sure you\'ve followed the instructions for this exercise exactly and are requesting only an access token.',
        $tokenResponse);
    }

    // Ensure a custom scope is returned
    if(!isset($response['scope'])) {
      return $this->_respondWithError($redirectToRoute,
        'No scopes were found in the response. Ensure you\'ve requested at least one of your custom scopes for this request.',
        $tokenResponse);
    }

    $scopesReturned = explode(' ', $response['scope']);
    if(!is_array($scopesReturned) || !count($scopesReturned) || !count(array_intersect($scopes, $scopesReturned))) {
      return $this->_respondWithError($redirectToRoute,
        'Make sure you\'ve requested one of the scopes you made public. You can find the list of scopes we\'re looking for in the first exercise.',
        $tokenResponse);
    }

    // Now parse the access token

    $tokenString = $response['access_token'];

    if(!preg_match('/^(.+)\.(.+)\.(.+)$/', $tokenString, $match)) {
      return $this->_respondWithError($redirectToRoute,
        'The access token returned does not look like a JWT. This tool will only with with JWT access tokens.',
        $tokenString);
    }

    $header = json_decode(base64_decode($match[1]), true);
    $claims = json_decode(base64_decode($match[2]), true);

    if(!$claims || !is_array($claims)) {
      return $this->_respondWithError($redirectToRoute,
        'Something went wrong trying to parse the claims in the token.',
        $tokenString);
    }

    $claimsString = json_encode($claims, JSON_PP);

    // Check for a uid and sub claim
    if(!isset($claims['uid']) || !isset($claims['sub'])) {
      return $this->_respondWithError($redirectToRoute,
        'The access token is missing some required claims. Try again by using the authorization code flow.',
        $claimsString);
    }

    // Check that the sub is an email. This is expected for Okta access tokens
    if(!preg_match('/.+@.+\..+/', $claims['sub'])) {
      return $this->_respondWithError($redirectToRoute,
        'The `sub` claim in Okta access tokens is an email address. Make sure you are getting a user to log in and using the authorization code flow.',
        $claimsString);
    }

    // Now attempt to verify the token using the JWKs from the metadata URL
    try {
      $tokenData = JWT::decode($tokenString, JWK::parseKeySet($this->session->get('jwks')), ['RS256']);
    } catch(\Exception $e) {
      return $this->_respondWithError($redirectToRoute,
        'There was an error validating the JWT: '.$e->getMessage(),
        $claimsString);
    }

    $this->_updateEmailForIssuer($claims['sub']);

    // Attempt to introspect the token, which should fail, since introspection in this case requires a client secret.
    // This is how we can check that they used a confidential client for this exercise and not a public client.
    try {
      $client = new GuzzleHttp\Client();
      $res = $client->request('POST', $this->session->get('introspection_endpoint'), [
        'http_errors' => false,
        'form_params' => [
          'token' =>$tokenString,
          'client_id' => $claims['cid'],
        ],
      ]);
    } catch(\Exception $e) {
      return $this->_respondWithError($redirectToRoute,
        'There was an unexpected error when validating this request: '.$e->getMessage(),
        $claimsString);
    }
    $code = $res->getStatusCode();

    if($code != 401) {
      return $this->_respondWithError($redirectToRoute,
        'We tried introspecting the token and it succeeded, indicating this access token was issued to a public client. Make sure you\'ve chosen "Web Application" when creating this app so that you have a client secret. ',
        $claimsString);
    }


    $this->session->set('complete_web', true);

    // Everything checked out, log a success
    return $this->_respondWithSuccess(
      $redirectToRoute,
      'Great! The access token is valid! You\'ve completed this exercise!',
      $claimsString
    );
  }

}
