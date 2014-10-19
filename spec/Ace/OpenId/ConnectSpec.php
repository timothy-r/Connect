<?php namespace spec\Ace\OpenId;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

use Lcobucci\JWT\Parser as JWTParser;
use Lcobucci\JWT\Token as JWTToken;

use Ace\Session;
use Ace\StoreInterface;

use Ace\Token\Csrf;
use Ace\Token\Nonce;

class ConnectSpec extends ObjectBehavior
{
    public function let(Session $session, StoreInterface $store, JWTParser $parser)
    {
        $this->beConstructedWith($session, $store, $parser);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType('Ace\OpenId\Connect');
    }

    public function it_stores_tokens_locally(Session $session)
    {   
        $redirect_uri = 'https://my.host.com/page';
        $csrf_key = 'authn.csrf.token';
        $nonce_key = 'authn.nonce.token';
        $session->store($csrf_key, Argument::any())->shouldBeCalled();
        $session->store($nonce_key, Argument::any())->shouldBeCalled();
        $this->generateRequestParameters($redirect_uri)->shouldBeArray();
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
        $nonce = 'invalid-nonce';
        $response = [
            'access_token' => 'xyz',
            'token_type' => 'bearer',
            'id_token' => 'value',
            'state' => $state,
            'nonce' => $nonce,
        ];
        $session->get('authn.csrf.token')->willReturn($state);
        $session->get('authn.nonce.token')->willReturn('zzz2');
        $store->contains($nonce)->willReturn(false);
        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }

    public function it_fails_validation_when_nonce_has_been_used(Session $session, StoreInterface $store)
    {
        $state = 'valid-state';
        $nonce = 'valid-nonce';
        $response = [
            'access_token' => 'xyz',
            'token_type' => 'bearer',
            'id_token' => 'value',
            'state' => $state,
            'nonce' => $nonce,
        ];
        $session->get('authn.csrf.token')->willReturn($state);
        $session->get('authn.nonce.token')->willReturn($nonce);
        $store->contains($nonce)->willReturn(true);
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
        $store->contains($nonce)->willReturn(false);

        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }

    public function it_fails_validation_when_id_token_fails_verification(Session $session, StoreInterface $store, JWTParser $parser, JWTToken $token)
    {
        $nonce = 'abcdef';
        $state = '123456';
        $id_token = 'invalid';
        $client_key = '';
        $response = [
            'access_token' => 'xyz',
            'token_type' => 'bearer',
            'id_token' => $id_token,
            'state' => $state,
            'nonce' => $nonce,
        ];
        $session->get('authn.csrf.token')->willReturn($state);
        $session->get('authn.nonce.token')->willReturn($nonce);
        $store->add($nonce)->shouldBeCalled();
        $store->contains($nonce)->willReturn(false);

        // mock the claims object returned from parse()
        $parser->parse($id_token)->willReturn($token);
        $token->verify(Argument::any())->willReturn(false);
        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }

    public function it_fails_validation_when_id_token_fails_validation(Session $session, StoreInterface $store, JWTParser $parser, JWTToken $token)
    {
        $nonce = 'abcdef';
        $state = '123456';
        $id_token = 'invalid';
        $client_key = '';
        $response = [
            'access_token' => 'xyz',
            'token_type' => 'bearer',
            'id_token' => $id_token,
            'state' => $state,
            'nonce' => $nonce,
        ];
        $session->get('authn.csrf.token')->willReturn($state);
        $session->get('authn.nonce.token')->willReturn($nonce);
        $store->add($nonce)->shouldBeCalled();
        $store->contains($nonce)->willReturn(false);

        // mock the claims object returned from parse()
        $parser->parse($id_token)->willReturn($token);
        $token->verify(Argument::any())->willReturn(true);
        $token->getClaims()->willReturn(['sub' => 'abc']);
        $token->validate(Argument::any(), Argument::any(), 'abc')->willReturn(false);

        $this->shouldThrow('Ace\OpenId\ResponseException')->during('validateResponseParameters', array($response));
    }

    public function it_passes_validation_when_request_is_valid(Session $session, StoreInterface $store, JWTParser $parser, JWTToken $token)
    {
        $nonce = 'abcdef';
        $state = '123456';
        $id_token = 'invalid';
        $client_key = '';
        $response = [
            'access_token' => 'xyz',
            'token_type' => 'bearer',
            'id_token' => $id_token,
            'state' => $state,
            'nonce' => $nonce,
        ];
        $session->get('authn.csrf.token')->willReturn($state);
        $session->get('authn.nonce.token')->willReturn($nonce);
        
        $store->contains($nonce)->willReturn(false);
        $store->add($nonce)->shouldBeCalled();

        // mock the claims object returned from parse()
        $parser->parse($id_token)->willReturn($token);
        $token->verify(Argument::any())->willReturn(true);
        $token->getClaims()->willReturn(['sub' => 'abc']);
        $token->validate(Argument::any(), Argument::any(), 'abc')->willReturn(true);
    
        $this->validateResponseParameters($response)->shouldReturn(true);
    }

    public function it_logs_user_out_locally(Session $session)
    {
        $session->store('authn.logout.local', 1)->shouldBeCalled();
        $this->logoutLocally();
    }
}
