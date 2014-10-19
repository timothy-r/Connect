<?php namespace Ace\OpenId;

use Lcobucci\JWT\Parser as JWTParser;
use Ace\OpenId\ResponseException;

use Ace\Token;
use Ace\Session;
use Ace\StoreInterface;

class Connect
{
    private static $issuer = 'https://authn.server.com';

    private static $client_id = 'Client';

    private static $client_key = '13d63cd20abaabdc148c46fc71566636';
    
    private static $csrf_session_key = 'authn.csrf.token';

    private static $nonce_session_key = 'authn.nonce.token';

    private $session;
    
    private $nonce_store;
    
    private $id_token_parser;

    public function __construct(Session $session, StoreInterface $nonce_store, JWTParser $parser)
    {
        $this->session = $session;
        $this->nonce_store = $nonce_store;
        $this->id_token_parser = $parser;
    }

    public function localTokensExist()
    {
        return $this->session->has(self::$csrf_session_key) && $this->session->has(self::$nonce_session_key);
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
            'state' => $this->generateSessionToken(self::$csrf_session_key),
            'nonce' => $this->generateSessionToken(self::$nonce_session_key),
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
        if (!$this->validateTokenType($parameters['token_type'])){
            throw new ResponseException("'token_type' parameter is invalid");
        }

        if (!$this->validateCsrfToken($parameters['state'])){
            throw new ResponseException("'state' parameter is invalid");
        }

        if (!$this->validateNonceToken($parameters['nonce'])){
            throw new ResponseException("'nonce' parameter is invalid");
        }

        // add the new nonce value to the store to prevent it being used again
        $this->nonce_store->add($parameters['nonce']);

        if (!$this->validateIdToken($parameters['id_token'])){
            throw new ResponseException("'id_token' parameter is invalid");
        }

        return true;
    }
    
    private function validateIdToken($id_token)
    {
        $token  = $this->id_token_parser->parse($id_token);
        if (!$token->verify(self::$client_key)){
            return false;
        }

        $claims = $token->getClaims();
        if (!$token->validate(self::$issuer, self::$client_id, $claims['sub'])){
            return false;
        }
        return true;
    }

    private function validateTokenType($type) 
    {
        return 'bearer' == strtolower($type);
    }

    private function validateCsrfToken($state)
    {
        $csrf = new Token($state);
        return $csrf->matches($this->session->get(self::$csrf_session_key));
    }

    private function validateNonceToken($nonce)
    {
        $nonce = new Token($nonce);
        if ($nonce->matches($this->session->get(self::$nonce_session_key))){
            // check nonce hasn't been used before
            return !$this->nonce_store->contains($nonce);
        } else {
            return false;
        }
    }

    private function generateSessionToken($session_key)
    {
        $token = new Token;
        $this->session->store($session_key, $token);
        return $token;
    }
    
    /**
    * Register that the user has logged out locally
    * Should really indicate the the user is now unauthenticated
    */
    public function logoutLocally()
    {
        $this->session->store('authn.logout.local', 1);
    }
}
