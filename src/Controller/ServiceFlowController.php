<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use ORM;

class ServiceFlowController extends ExerciseController {

  use AuthorizationFlowTrait;

  protected $pageTitle = 'Client Credentials Flow for Service Apps';
  protected $baseRoute = 'service';

  public function index(): Response {

    $issuer = $this->session->get('issuer');
    $scopes = $this->session->get('scopes');

    return $this->render('exercises/client-credentials.html.twig', [
      'page_title' => $this->pageTitle,
      'issuer' => $issuer,
      'scopes' => $scopes,
      'base_route' => $this->baseRoute,
    ]);
  }

  public function save(Request $request): Response {

    if($errorResponse = $this->_initialAccessTokenChecks($request, [
      'clientCredentials' => true
    ])) {
      return $errorResponse;
    }

    $provider = $this->_providerFromIssuer($this->session->get('issuer'));

    if($provider == 'okta') {
      // Should not include a uid
      if(isset($this->claims['uid'])) {
        return $this->_respondWithError($this->baseRoute,
          'The access token contains a uid claim which means it was not obtained with the client credentials grant. Try again!',
          $this->claimsString);
      }

      // sub should match cid for client credentials access tokens
      if(!isset($this->claims['cid']) || $this->claims['cid'] != $this->claims['sub']) {
        return $this->_respondWithError($this->baseRoute,
          'This access token looks like it was not issued with the client credentials grant. Try again!',
          $this->claimsString);
      }
    }

    if($provider == 'auth0') {
      // gty should be 'client-credentials'
      if(!isset($this->claims['gty']) || $this->claims['gty'] != 'client-credentials') {
        return $this->_respondWithError($this->baseRoute,
          'This access tokens looks like it was not issued with the client credentials grant, try again!',
          $this->claimsString);
      }

      // sub should match the @clients pattern
      if(!preg_match('/.+@clients/', $this->claims['sub'])) {
        return $this->_respondWithError($this->baseRoute,
          'This access tokens looks like it wasn\'t issued with the client credentials grant, try again!',
          $this->claimsString);
      }
    }

    $this->session->set('complete_service', true);

    // Everything checked out, log a success
    return $this->_respondWithSuccess(
      $this->baseRoute,
      'Great! The access token is valid! You\'ve completed this exercise!',
      $this->claimsString
    );
  }

}
