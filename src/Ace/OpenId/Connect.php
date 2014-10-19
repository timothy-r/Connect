<?php namespace Ace\OpenId;

use Ace\OpenId\ResponseException;

use Ace\Token\Csrf;
use Ace\Token\Nonce;
use Ace\Session;
use Ace\StoreInterface;

class Connect
{
    private static $client_id = 'Client';

    private $session;
    
    private $nonce_store;

    public function __construct(Session $session, StoreInterface $nonce_store)
    {
        $this->session = $session;
        $this->nonce_store = $nonce_store;
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
        if($nonce->matches($this->session->get('authn.nonce.token'))){
            // check nonce hasn't been used before
            return !$this->nonce_store->contains($nonce);
        } else {
            return false;
        }
    }

    /**
    * Get all the parameters to make a request to central authn
    * @return array
    */
    public function generateRequestParameters($redirect_uri)
    {
        return [
            'response_type' => 'id_token token',
            'client_id' => self::$client_id,
            'redirect_uri' => $redirect_uri,
            'scope' => 'openid',
            'state' => $this->generateCsrfToken(),
            'nonce' => $this->generateNonceToken(),
        ];
    }
    
    /**
    * validate necessary response parameters are set and have correct values
    */
    public function validateResponse(array $parameters)
    {
        if (!isset($parameters['access_token'])){
            throw new ResponseException("'access_token' parameter must be set");
        }
    }
}
