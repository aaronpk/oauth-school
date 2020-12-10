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
      'introduction', 'web',
    ];
    $status = [];
    foreach($exercises as $key) {
      $status[$key] = $this->session->get('complete_'.$key);
    }

    return $this->render('index.html.twig', [
      'status' => $status,
    ]);
  }

  public function logout(): Response {
    $this->session->clear();
    return $this->redirectToRoute('index');
  }

}
