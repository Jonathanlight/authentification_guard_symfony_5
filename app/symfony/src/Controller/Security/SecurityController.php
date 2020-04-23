<?php

namespace App\Controller\Security;

use App\Entity\User;
use App\Form\Security\LoginType;
use App\Form\Security\RegisterType;
use App\Form\Security\RequestType;
use App\Form\Security\ResetType;
use App\Manager\TokenManager;
use App\Manager\UserManager;
use App\Services\MessageService;
use App\Services\PasswordService;
use App\Services\TokenService;
use App\Services\TranslatorService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\ParamConverter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    /**
     * @Route("/", name="home", methods={"GET","POST"})
     * @param Request $request
     * @return Response
     * @throws \Exception
     */
    public function default(
        Request $request
    ): Response {
        return $this->render('default.html.twig');
    }

    /**
     * @Route("/user/connect", name="dashboard", methods={"GET","POST"})
     * @param Request $request
     * @return Response
     * @throws \Exception
     */
    public function dashboard(
        Request $request
    ): Response {
        return $this->render('dashboard.html.twig');
    }

    /**
     * @Route("/user/login", name="login", methods={"GET","POST"})
     * @param AuthenticationUtils $authUtils
     * @param Request $request
     * @return Response
     * @throws \Exception
     */
    public function user(
        AuthenticationUtils $authUtils,
        Request $request
    ): Response {
        if ($this->getUser()) {
            return $this->redirectToRoute('dashboard');
        }

        $form = $this->createForm(LoginType::class, [
            '_username' => $authUtils->getLastUsername(),
        ]);

        return $this->render('security/login.html.twig', [
            'error' => $authUtils->getLastAuthenticationError(),
            'form' => $form->createView(),
        ]);
    }

    /**
     * @Route("/user/register", name="register", methods={"GET", "POST"})
     * @param Request $request
     * @param PasswordService $passwordService
     * @param EntityManagerInterface $em
     * @return \Symfony\Component\HttpFoundation\RedirectResponse|Response
     */
    public function register_user(
        Request $request,
        PasswordService $passwordService,
        EntityManagerInterface $em
    ) {
        if ($this->getUser()) {
            return $this->redirectToRoute('home');
        }

        $user = new User();
        $user->setRole(User::ROLE_USER);

        $form = $this->createForm(RegisterType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {

            $user->setUsername($user->getEmail());
            $pass = $passwordService->encode($user, $user->getPassword());
            $user->setPassword($pass);
            $user->setReference(uniqid());
            $em->persist($user);
            $em->flush();

            return $this->redirectToRoute('login');
        }

        return $this->render('security/register.html.twig', [
            'form' => $form->createView()
        ]);
    }

    /**
     * @Route("/user/logout", name="user_logout", methods={"GET"})
     */
    public function logout()
    {
        throw new \RuntimeException('You must activate the logout in your security firewall configuration.');
    }
}