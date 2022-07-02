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
    $step2  = $this->session->get('step2');
    $authorization_endpoint = $this->session->get('authorization_endpoint');
    $token_endpoint = $this->session->get('token_endpoint');

    return $this->render('exercises/introduction.html.twig', [
      'issuer' => $issuer,
      'scopes' => $scopes,
      'step2' => $step2,
      'scopeString' => implode(' ', $scopes ?: []),
      'numScopes' => count($scopes ?: []),
      'authorization_endpoint' => $authorization_endpoint,
      'token_endpoint' => $token_endpoint,
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


    // First fetch the OAuth server metadata
    $metadataURL = $issuer.'/.well-known/oauth-authorization-server';
    list($metadata, $error) = $this->_fetchMetadataURL($metadataURL);

    if($error) {
      // Try fetching the OpenID Configuration next
      $metadataURL = $issuer.'/.well-known/openid-configuration';
      list($metadata, $error) = $this->_fetchMetadataURL($metadataURL);

      if($error) {
        return $this->_respondWithError($redirectToRoute, $error, $issuer);
      }
    }

    // Check for the JWKs URL
    if(!isset($metadata['jwks_uri'])) {
      return $this->_respondWithError($redirectToRoute,
        'The metadata URL does not contain a jwks_uri',
        $issuer);
    }

    $host = parse_url($issuer, PHP_URL_HOST);

    $provider = 'unknown';
    if(preg_match('/.+\.okta\.com$/', $host))
      $provider = 'okta';
    if(preg_match('/.+\.auth0\.com$/', $host))
      $provider = 'auth0';

    $client = new GuzzleHttp\Client();

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
    $oktaScopes   = ['device_sso'];
    $auth0Scopes  = ['name','given_name','family_name','nickname','email_verified','created_at','identities','picture'];

    if($provider == 'okta') {
      $customScopes = array_diff($metadata['scopes_supported'], array_merge($openIDScopes,$oktaScopes));

      if(count($customScopes) == 0) {
        return $this->_respondWithError($redirectToRoute,
          'We didn\'t find any custom scopes defined on your OAuth server. Ensure you\'ve created at least one custom scope and set it to "Include in public metadata".',
          $issuer);
      }

    } elseif($provider == 'auth0') {
      $customScopes = array_diff($metadata['scopes_supported'], array_merge($openIDScopes,$auth0Scopes));
      // Auth0 doesn't return the scopes in the public OIDC metadata so we can't verify at this stage
    } else {
      $customScopes = array_diff($metadata['scopes_supported'], $openIDScopes);
    }

    $count = count($customScopes);

    $this->session->set('issuer', $issuer);
    $this->session->set('scopes', $customScopes);
    $this->session->set('jwks', $jwks);
    $this->session->set('introspection_endpoint', $metadata['introspection_endpoint'] ?? null);
    $this->session->set('expected_authorization_endpoint', $metadata['authorization_endpoint'] ?? null);
    $this->session->set('expected_token_endpoint', $metadata['token_endpoint'] ?? null);

    $record = ORM::for_table('issuers')->where('uri', $issuer)->find_one();
    if(!$record) {
      $record = ORM::for_table('issuers')->create();
      $record->created_at = date('Y-m-d H:i:s');
      $record->uri = $issuer;
    }
    $record->scopes = substr(implode(' ', $customScopes), 0, 255);
    $record->last_logged_in_at = date('Y-m-d H:i:s');
    $record->save();

    if($provider == 'okta')
      $successMessage = 'Great! Your issuer URL is accepted and we found '.$count.' custom scopes!';
    else
      $successMessage = 'Great! Your issuer URL is accepted!';

    $this->session->set('step2', true);

    return $this->_respondWithSuccess($redirectToRoute,
      $successMessage,
      json_encode(['iss'=>$issuer, 'scopes'=>$customScopes], JSON_PP));
  }

  private function _fetchMetadataURL($metadataURL) {

    // Fetch the URL
    try {
      $client = new GuzzleHttp\Client();
      $res = $client->request('GET', $metadataURL, [
        'http_errors' => false,
      ]);
    } catch(\Exception $e) {
      return [null, 'There was an error trying to fetch the OAuth server metadata: '.$e->getMessage()];
    }
    $code = $res->getStatusCode();

    if($code != 200) {
      return [null, 'The metadata URL ('.$metadataURL.') returned HTTP '.$code.'. Double check you entered the correct issuer URL'];
    }

    $metadata = json_decode($res->getBody(), true);

    if(!$metadata) {
      return [null, 'The metadata URL does not contain valid JSON'];
    }

    return [$metadata, null];
  }

  public function check(Request $request): Response {

    $redirectToRoute = 'introduction';

    $expected_authorization_endpoint = $this->session->get('expected_authorization_endpoint');
    $expected_token_endpoint = $this->session->get('expected_token_endpoint');

    // Check that the endpoints they entered match what we expect from the metadata URL

    if(!$this->session->get('authorization_endpoint')) {
      $authorization_endpoint = $request->request->get('authorization_endpoint');

      if($authorization_endpoint != $expected_authorization_endpoint) {
        return $this->_respondWithError($redirectToRoute,
          'The authorization endpoint you entered is not correct, try again!',
          json_encode(['entered' => $authorization_endpoint, 'expected' => $expected_authorization_endpoint], JSON_PP)
        );
      }

      $this->session->set('authorization_endpoint', $authorization_endpoint);
    }

    if(!$this->session->get('token_endpoint')) {
      $token_endpoint = $request->request->get('token_endpoint');

      if($token_endpoint != $expected_token_endpoint) {
        return $this->_respondWithError($redirectToRoute,
          'The token endpoint you entered is not correct, try again!',
          json_encode(['entered' => $token_endpoint, 'expected' => $expected_token_endpoint], JSON_PP)
        );
      }

      $this->session->set('token_endpoint', $token_endpoint);
    }

    $this->session->set('complete_introduction', true);

    return $this->_respondWithSuccess($redirectToRoute,
      'Great! You\'ve found the authorization and token endpoints!',
      json_encode(['authorization_endpoint'=>$expected_authorization_endpoint, 'token_endpoint'=>$expected_token_endpoint], JSON_PP));

    return $this->redirectToRoute('introduction');
  }

}
