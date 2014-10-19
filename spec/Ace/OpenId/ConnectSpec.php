<?php namespace spec\Ace\OpenId;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

use Ace\Session;
use Ace\StoreInterface;

use Ace\Token\Csrf;
use Ace\Token\Nonce;

class ConnectSpec extends ObjectBehavior
{
    public function let(Session $session, StoreInterface $store)
    {
        $this->beConstructedWith($session, $store);
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

    public function it_fails_validation_when_neither_token_is_stored_locally(Session $session)
    {
        $session->has('authn.csrf.token')->willReturn(false);
        $session->has('authn.nonce.token')->willReturn(false);
        $this->localTokensExist()->shouldReturn(false);
    }

    public function it_fails_validation_when_csrf_token_is_not_stored_locally(Session $session)
    {
        $session->has('authn.csrf.token')->willReturn(false);
        $session->has('authn.nonce.token')->willReturn(true);
        $this->localTokensExist()->shouldReturn(false);
    }

    public function it_fails_validation_when_nonce_token_is_not_stored_locally(Session $session)
    {
        $session->has('authn.csrf.token')->willReturn(true);
        $session->has('authn.nonce.token')->willReturn(false);
        $this->localTokensExist()->shouldReturn(false);
    }

    public function it_passes_validation_when_tokens_are_stored_locally(Session $session)
    {
        $session->has('authn.csrf.token')->willReturn(true);
        $session->has('authn.nonce.token')->willReturn(true);
        $this->localTokensExist()->shouldReturn(true);
    }

    public function it_generates_all_request_parameters(Session $session)
    {
        $redirect_uri = 'https://my.host.com/page';

        $this->generateRequestParameters($redirect_uri)->shouldBeArray();
        $this->generateRequestParameters($redirect_uri)->shouldHaveKey('response_type');
        $this->generateRequestParameters($redirect_uri)->shouldHaveKey('client_id');
        $this->generateRequestParameters($redirect_uri)->shouldHaveKey('redirect_uri');
        $this->generateRequestParameters($redirect_uri)->shouldHaveKey('scope');
        $this->generateRequestParameters($redirect_uri)->shouldHaveKey('state');
        $this->generateRequestParameters($redirect_uri)->shouldHaveKey('nonce');
    }

    public function it_fails_validation_when_response_is_empty(Session $session, StoreInterface $store)
    {
        $response = [];
        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }

    public function it_fails_validation_when_token_type_is_missing(Session $session, StoreInterface $store)
    {
        $response = [
            'access_token' => 'xyz',
            'id_token' => 'value',
            'nonce' => 'abcdef',
            'state' => '123456',
        ];
        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }

    public function it_fails_validation_when_token_type_is_invalid(Session $session, StoreInterface $store)
    {
        $response = [
            'access_token' => 'xyz',
            'id_token' => 'value',
            'token_type' => 'garbage',
            'nonce' => 'abcdef',
            'state' => '123456',
        ];
        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }

    public function it_fails_validation_when_id_token_is_missing(Session $session, StoreInterface $store)
    {
        $response = [
            'access_token' => 'xyz',
            'token_type' => 'bearer',
            'nonce' => 'abcdef',
            'state' => '123456',
        ];
        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }

    public function it_fails_validation_when_nonce_is_missing(Session $session, StoreInterface $store)
    {
        $response = [
            'access_token' => 'xyz',
            'token_type' => 'bearer',
            'id_token' => 'value',
            'state' => '123456'
        ];
        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }

    public function it_fails_validation_when_nonce_is_invalid(Session $session, StoreInterface $store)
    {
        $state = '123456';
        $response = [
            'access_token' => 'xyz',
            'token_type' => 'bearer',
            'id_token' => 'value',
            'state' => $state,
            'nonce' => 'abcdef',
        ];
        $session->get('authn.csrf.token')->willReturn($state);
        $session->get('authn.nonce.token')->willReturn('zzz2');
        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }

    public function it_fails_validation_when_state_is_missing(Session $session, StoreInterface $store)
    {
        $response = [
            'access_token' => 'xyz',
            'token_type' => 'bearer',
            'id_token' => 'value',
            'nonce' => 'abcdef'
        ];
        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }

    public function it_fails_validation_when_state_is_invalid(Session $session, StoreInterface $store)
    {
        $nonce = 'abcdef';
        $response = [
            'access_token' => 'xyz',
            'token_type' => 'bearer',
            'id_token' => 'value',
            'state' => '123456',
            'nonce' => $nonce,
        ];
        $session->get('authn.csrf.token')->willReturn('xxx');
        $session->get('authn.nonce.token')->willReturn($nonce);
        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }
}
