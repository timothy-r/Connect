<?php namespace spec\Ace\OpenId;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Ace\Session;


class ConnectSpec extends ObjectBehavior
{
    public function let(Session $session)
    {
        $this->beConstructedWith($session);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType('Ace\OpenId\Connect');
    }

    public function it_generates_csrf_token()
    {
        $this->generateCsrfToken()->shouldHaveType('Ace\Token\Csrf');
    }

    public function it_generates_nonce_token()
    {
        $this->generateNonceToken()->shouldHaveType('Ace\Token\Nonce');
    }

    public function it_stores_csrf_token_locally(Session $session)
    {   
        $csrf_key = 'authn.csrf.token';
        $session->store($csrf_key, Argument::any())->shouldBeCalled();
        $this->generateCsrfToken();
    }

    public function it_stores_nonce_token_locally(Session $session)
    {   
        $nonce_key = 'authn.nonce.token';
        $session->store($nonce_key, Argument::any())->shouldBeCalled();
        $this->generateNonceToken();
    }

    public function it_validates_tokens_are_stored_locally()
    {

    }

    public function it_validates_tokens_match()
    {

    }

    public function it_validates_nonce_is_not_reused()
    {

    }
}
