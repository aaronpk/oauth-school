<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use ORM;

class NativeFlowController extends ExerciseController {

  use AuthorizationFlowTrait;

  protected $pageTitle = 'Authorization Code Flow for Native Apps';
  protected $baseRoute = 'native';
  protected static $baseRouteStatic = 'native';

  public function save(Request $request): Response {

    if($errorResponse = $this->_initialAccessTokenChecks($request)) {
      return $errorResponse;
    }

    // Attempt to introspect the token, which should succeed, since introspection in this case does not require a client secret.
    // This is how we can check that they used a public client for this exercise and not a confidential client.
    // We can't tell the difference between a native app and SPA app though.
    try {
      $client = new GuzzleHttp\Client();
      $res = $client->request('POST', $this->session->get('introspection_endpoint'), [
        'http_errors' => false,
        'form_params' => [
          'token' =>$this->tokenString,
          'client_id' => $this->claims['cid'],
        ],
      ]);
    } catch(\Exception $e) {
      return $this->_respondWithError($this->baseRoute,
        'There was an unexpected error when validating this request: '.$e->getMessage(),
        $this->claimsString);
    }
    $code = $res->getStatusCode();

    if($code != 200) {
      return $this->_respondWithError($this->baseRoute,
        'We tried introspecting the token and it failed, indicating this access token was issued to a confidential client. Make sure you\'ve chosen "Native Application" when creating this app.',
        $this->claimsString);
    }

    $this->session->set('complete_'.static::$baseRouteStatic, true);

    // Everything checked out, log a success
    return $this->_respondWithSuccess(
      $this->baseRoute,
      'Great! The access token is valid! You\'ve completed this exercise!',
      $this->claimsString
    );
  }

}
