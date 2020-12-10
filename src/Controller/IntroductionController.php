<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use ORM;

class IntroductionController extends ExerciseController {

  public function index(): Response {

    $issuer = $this->session->get('issuer');
    $scopes = $this->session->get('scopes');

    return $this->render('exercises/introduction.html.twig', [
      'issuer' => $issuer,
      'scopes' => $scopes,
      'scopeString' => implode(' ', $scopes ?: []),
      'numScopes' => count($scopes ?: []),
    ]);
  }

  public function save(Request $request): Response {

    $redirectToRoute = 'introduction';

    $issuer = $request->request->get('issuer');

    if(!$issuer) {
      return $this->_respondWithError($redirectToRoute,
        'Please provide an issuer URL',
        $issuer);
    }

    // Check that it's a URL
    if(!preg_match('/^https?:\/\/[^\/]+/', $issuer)) {
      return $this->_respondWithError($redirectToRoute,
        'The issuer identifier must be a URL',
        $issuer);
    }

    $metadataURL = $issuer.'/.well-known/oauth-authorization-server';

    // Fetch the URL
    try {
      $client = new GuzzleHttp\Client();
      $res = $client->request('GET', $metadataURL, [
        'http_errors' => false,
      ]);
    } catch(\Exception $e) {
      return $this->_respondWithError($redirectToRoute,
        'There was an error trying to fetch the OAuth server metadata: '.$e->getMessage(),
        $issuer);
    }
    $code = $res->getStatusCode();

    if($code != 200) {
      return $this->_respondWithError($redirectToRoute,
        'The metadata URL ('.$metadataURL.') returned HTTP '.$code.'. Double check you entered the correct issuer URL',
        $issuer);
    }

    $metadata = json_decode($res->getBody(), true);

    if(!$metadata) {
      return $this->_respondWithError($redirectToRoute,
        'The metadata URL does not contain valid JSON',
        $issuer);
    }

    // Check for the JWKs URL
    if(!isset($metadata['jwks_uri'])) {
      return $this->_respondWithError($redirectToRoute,
        'The metadata URL does not contain a jwks_uri',
        $issuer);
    }

    // Attempt to fetch the keys
    $jwksres = $client->request('GET', $metadata['jwks_uri'], [
      'http_errors' => false,
    ]);
    $code = $jwksres->getStatusCode();

    if($code != 200) {
      return $this->_respondWithError($redirectToRoute,
        'The jwks_uri ('.$metadata['jwks_uri'].') returned HTTP '.$code.'. Double check you entered the correct issuer URL',
        $issuer);
    }

    $jwks = json_decode($jwksres->getBody(), true);

    if(!$jwks) {
      return $this->_respondWithError($redirectToRoute,
        'The jwks_uri does not contain valid JSON',
        $issuer);
    }

    // Check for the custom scope
    if(!isset($metadata['scopes_supported'])) {
      return $this->_respondWithError($redirectToRoute,
        'The metadata URL does not contain the "scopes_supported" property',
        $issuer);
    }

    $openIDScopes = ['openid','profile','email','address','phone','offline_access'];
    $customScopes = array_diff($metadata['scopes_supported'], $openIDScopes);
    if(count($customScopes) == 0) {
      return $this->_respondWithError($redirectToRoute,
        'We didn\'t find any custom scopes defined on your OAuth server. Ensure you\'ve created at least one custom scope and set it to "Include in public metadata".',
        $issuer);
    }

    $count = count($customScopes);
    $this->session->set('issuer', $issuer);
    $this->session->set('scopes', $customScopes);
    $this->session->set('jwks', $jwks);

    $record = ORM::for_table('issuers')->where('uri', $issuer)->find_one();
    if(!$record) {
      $record = ORM::for_table('issuers')->create();
      $record->created_at = date('Y-m-d H:i:s');
      $record->uri = $issuer;
    }
    $record->scopes = substr(implode(' ', $customScopes), 0, 255);
    $record->last_logged_in_at = date('Y-m-d H:i:s');
    $record->save();

    return $this->_respondWithSuccess($redirectToRoute,
      'Great! Your issuer URL is accepted and we found '.$count.' custom scopes!',
      json_encode(['iss'=>$issuer, 'scopes'=>$customScopes], JSON_PP));

    return $this->redirectToRoute('introduction');
  }

}
