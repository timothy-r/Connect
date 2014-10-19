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

    private function validateCsrfToken(Csrf $csrf)
    {
        return $csrf->matches($this->session->get('authn.csrf.token'));
    }

    private function validateNonceToken(Nonce $nonce)
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
    public function validateResponseParameters(array $parameters)
    {
        // validate that expected keys are set
        $required_keys = ['access_token', 'token_type', 'id_token', 'nonce', 'state'];
        foreach ($required_keys as $key) {
            if (!isset($parameters[$key])){
                throw new ResponseException("'$key' parameter must be set");
            }
        }
    
        // validate key values
        if ('bearer' != $parameters['token_type']){
            throw new ResponseException("'token_type' parameter must equal 'bearer'");
        }

        if (!$this->validateCsrfToken(new Csrf($parameters['state']))){
            throw new ResponseException("'state' parameter is invalid");
        }

        if (!$this->validateNonceToken(new Nonce($parameters['nonce']))){
            throw new ResponseException("'nonce' parameter is invalid");
        }
    }
}
