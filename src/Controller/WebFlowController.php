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

    if($errorResponse = $this->_initialAccessTokenChecks($request)) {
      return $errorResponse;
    }

    // Attempt to introspect the token, which should fail, since introspection in this case requires a client secret.
    // This is how we can check that they used a confidential client for this exercise and not a public client.
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
      return $this->_respondWithError($redirectToRoute,
        'There was an unexpected error when validating this request: '.$e->getMessage(),
        $this->claimsString);
    }
    $code = $res->getStatusCode();

    if($code != 401) {
      return $this->_respondWithError($redirectToRoute,
        'We tried introspecting the token and it succeeded, indicating this access token was issued to a public client. Make sure you\'ve chosen "Web Application" when creating this app so that you have a client secret. ',
        $this->claimsString);
    }

    $this->session->set('complete_web', true);

    // Everything checked out, log a success
    return $this->_respondWithSuccess(
      $redirectToRoute,
      'Great! The access token is valid! You\'ve completed this exercise!',
      $this->claimsString
    );
  }

}
