<?php namespace Ace\OpenId;

use Ace\Token\Csrf;
use Ace\Token\Nonce;
use Ace\Session;

class Connect
{
    private $session;

    public function __construct(Session $session)
    {
        $this->session = $session;
    }

    public function generateCsrfToken()
    {
        $csrf = new Csrf;
        $key = 'authn.csrf.token';
        $this->session->store($key, $csrf);
        return $csrf;
    }

    public function generateNonceToken()
    {
        $nonce = new Nonce;
        $key = 'authn.nonce.token';
        $this->session->store($key, $nonce);
        return $nonce;
    }

    public function localTokensExist()
    {
        return $this->session->has('authn.csrf.token') && $this->session->has('authn.nonce.token');
    }

    public function validateCsrfToken(Csrf $csrf)
    {
        return $csrf->matches($this->session->get('authn.csrf.token'));
    }

    public function validateNonceToken(Nonce $nonce)
    {
        return $nonce->matches($this->session->get('authn.nonce.token'));
    }
}
