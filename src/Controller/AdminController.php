<?php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use GuzzleHttp;
use ORM;

class AdminController extends AbstractController {

  private $session;

  public function __construct(SessionInterface $session)
  {
    $this->session = $session;
  }

  private function _requireLogin() {
    if(!$this->session->get('admin_user_id')) {
      return $this->redirectToRoute('admin');
    }
  }

  public function index(): Response {
    return $this->render('admin/index.html.twig');
  }

  public function login_start(): Response {
    $this->session->set('state', bin2hex(random_bytes(10)));

    $this->session->set('code_verifier', $code_verifier = bin2hex(random_bytes(50)));
    $code_challenge = rtrim(strtr(base64_encode((hash('sha256', $code_verifier, true))), '+/', '-_'), '=');

    $params = [
      'response_type' => 'code',
      'scope' => 'openid profile',
      'state' => $this->session->get('state'),
      'redirect_uri' => $_ENV['OKTA_REDIRECT_URL'],
      'code_challenge' => $code_challenge,
      'code_challenge_method' => 'S256',
      'client_id' => $_ENV['OKTA_CLIENT_ID'],
    ];

    $authorizationURL = $_ENV['OKTA_AUTHORIZATION_ENDPOINT'] . '?' . http_build_query($params);

    return $this->redirect($authorizationURL);
  }

  public function login_callback(Request $request): Response {

    if($request->query->get('code')) {

      try {
        $client = new GuzzleHttp\Client();
        $res = $client->request('POST', $_ENV['OKTA_TOKEN_ENDPOINT'], [
          'http_errors' => false,
          'form_params' => [
            'grant_type' => 'authorization_code',
            'code' => $request->query->get('code'),
            'redirect_uri' => $_ENV['OKTA_REDIRECT_URL'],
            'code_verifier' => $this->session->get('code_verifier'),
            'client_id' => $_ENV['OKTA_CLIENT_ID'],
            'client_secret' => $_ENV['OKTA_CLIENT_SECRET'],
          ]
        ]);
      } catch(\Exception $e) {
        $this->addFlash('error', 'There was an error trying to log in: '.$e->getMessage());
        return $this->redirectToRoute('admin');
      }
      $code = $res->getStatusCode();

      if($code != 200) {
        $this->addFlash('error', 'There was an error trying to log in, token endpoint returned: '.$code);
        return $this->redirectToRoute('admin');
      }

      $info = json_decode($res->getBody(), true);

      if(!isset($info['id_token'])) {
        $this->addFlash('error', 'The token endpoint did not return an ID token');
        return $this->redirectToRoute('admin');
      }

      $claims_component = explode('.', $info['id_token'])[1];
      $userinfo = json_decode(base64_decode($claims_component), true);

      $this->session->set('admin_user_id', $userinfo['sub']);
      $this->session->set('admin_user_name', $userinfo['name']);
      $this->redirectToRoute('admin');

    } elseif($error=$request->query->get('error')) {
      $this->addFlash('error', $error);
    } else {
      $this->addFlash('error', 'An unknown error occurred during login');
    }

    return $this->redirectToRoute('admin');
  }

  public function challenge_winners(): Response {
    if($r=$this->_requireLogin())
      return $r;

    $winners = ORM::for_table('challenge_winners')->order_by_desc('created_at')->find_many();

    return $this->render('admin/challenge-winners.html.twig', [
      'winners' => $winners,
    ]);
  }

  public function challenge_winners_save(Request $request): Response {
    if($r=$this->_requireLogin())
      return $r;

    $archived = $request->request->get('archived') == 'archived' ? true : false;

    $winner = ORM::for_table('challenge_winners')->where('id', $request->request->get('winner_id'))->find_one();
    if($winner) {
      $winner->archived = $archived;
      $winner->save();
    }

    return $this->json([
      'saved' => true,
      'archived' => $archived,
    ]);
  }

}
