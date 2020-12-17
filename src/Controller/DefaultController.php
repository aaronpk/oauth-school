<?php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpFoundation\Response;

class DefaultController extends AbstractController {

  private $session;

  public function __construct(SessionInterface $session)
  {
    $this->session = $session;
  }

  public function index(): Response {

    $exercises = [
      'client' => [
        'introduction' => 'Getting Started',
        'web' => 'OAuth for Web Applications',
            #'native' => 'OAuth for Native Applications',
        #'spa' => 'OAuth for Single-Page Applications',
            #'device' => 'OAuth for IoT and Smart Devices',
        #'service' => 'OAuth for Machine-to-Machine Applications',
        'refresh' => 'Refresh Tokens',
        'openid' => 'OpenID Connect',
      ],
      'server' => [
        'api' => 'Protecting an API with OAuth',
        'revoke' => 'Revoking an Access Token',
        'scopes' => 'Enforcing Scopes in Your API',
      ],
    ];
    $status = [];
    foreach($exercises as $type=>$list) {
      foreach($list as $key=>$name) {
        $status[$key] = $this->session->get('complete_'.$key);
      }
    }

    return $this->render('index.html.twig', [
      'exercises' => $exercises,
      'status' => $status,
    ]);
  }

  public function logout(): Response {
    $this->session->clear();
    return $this->redirectToRoute('index');
  }

}
